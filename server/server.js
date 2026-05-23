require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const { Server } = require("socket.io");
const db = require("./db");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if(!JWT_SECRET){
  throw new Error("JWT_SECRET is required");
}
const usernameRegex = /^[A-Za-z0-9]{3,16}$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{6,14}$/;

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((req,res,next)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Referrer-Policy","same-origin");
  res.setHeader("Permissions-Policy","camera=(), microphone=(), geolocation=()");
  next();
});
app.use(express.json());
app.use(morgan("combined"));
app.use(express.static(path.join(__dirname,"..","public"),{
  etag:true,
  maxAge: process.env.NODE_ENV === "production" ? "1h" : 0
}));

app.get("/healthz",(req,res)=>{
  res.json({ ok:true });
});

function verifyToken(req){
  const auth = req.headers.authorization;
  if(!auth) return null;
  try{
    const payload = jwt.verify(auth, JWT_SECRET);
    return payload.id;
  } catch(err){
    return null;
  }
}

function auth(req,res,next){
  const token = req.headers.authorization;
  if(!token) return res.status(401).json({ error:"Unauthorized" });
  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch{
    return res.status(401).json({ error:"Invalid Token" });
  }
}

app.post("/api/register", async (req,res)=>{
  const {username,password} = req.body;

  if(!usernameRegex.test(username))
    return res.status(400).json({ error:"Invalid username" });

  if(!passwordRegex.test(password))
    return res.status(400).json({ error:"Invalid password" });

  const hash = await bcrypt.hash(password,10);

  db.run(
    "INSERT INTO users(username,password_hash) VALUES(?,?)",
    [username,hash],
    function(err){
      if(err){
        return res.status(400).json({ error:"Username exists" });
      }
      res.json({ success:true });
    }
  );
});

app.post("/api/login",(req,res)=>{
  const {username,password} = req.body;
  if(!usernameRegex.test(username) || !passwordRegex.test(password)){
    return res.status(401).json({ error:"Invalid credentials" });
  }
  db.get(
    "SELECT * FROM users WHERE username=?",
    [username],
    async (err,user)=>{
      if(!user)
        return res.status(401).json({ error:"Invalid credentials" });

      const ok = await bcrypt.compare(password,user.password_hash);
      if(!ok)
        return res.status(401).json({ error:"Invalid credentials" });

      const token = jwt.sign({id:user.id}, JWT_SECRET, { expiresIn: "7d" });
      res.json({ token });
    }
  );
});

app.get("/api/check-username",(req,res)=>{
  const username = String(req.query.username||"").trim();
  if(!usernameRegex.test(username)){
    return res.status(400).json({ available:false, error:"Username must be 6-14 letters and numbers only" });
  }
  db.get("SELECT id FROM users WHERE username=?", [username], (err,row)=>{
    if(err) return res.status(500).json({ available:false, error:"Unable to check username" });
    res.json({ available: !row });
  });
});

app.post("/api/score", auth, (req,res)=>{
  const userId = req.user.id;
  const score = req.body.score;
  const level = req.body.level;

  if(typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 1000000){
    return res.status(400).json({ error:"Invalid score" });
  }
  if(typeof level !== "number" || !Number.isInteger(level) || level < 1 || level > 999){
    return res.status(400).json({ error:"Invalid level" });
  }

  const gameStartedAt = req.body.gameStartedAt;
  if(gameStartedAt){
    const startedTime = Number.isFinite(gameStartedAt) ? gameStartedAt : Date.parse(gameStartedAt);
    if(!Number.isFinite(startedTime) || startedTime > Date.now()){
      return res.status(400).json({ error:"Invalid gameStartedAt" });
    }
    const secondsPlayed = Math.max(1, Math.floor((Date.now() - startedTime)/1000));
    if(score > secondsPlayed * 500){
      return res.status(400).json({ error:"Invalid score" });
    }
  }

  db.run(
    `INSERT INTO scores(user_id,score,level,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)`,
    [userId, score, level],
    function(err){
      if(err) return res.status(500).json({ error:"Unable to save score" });

      db.run(
        `UPDATE users SET
           games_played = games_played + 1,
           highest_score = CASE WHEN ? > highest_score THEN ? ELSE highest_score END,
           highest_level = CASE WHEN ? > highest_level THEN ? ELSE highest_level END
         WHERE id = ?`,
        [score, score, level, level, userId],
        function(err2){
          if(err2) return res.status(500).json({ error:"Unable to update stats" });
          res.json({ success:true });
        }
      );
    }
  );
});

app.get("/api/leaderboard",(req,res)=>{
  db.all(`
    SELECT u.username, MAX(s.score) score
    FROM scores s
    JOIN users u ON s.user_id=u.id
    GROUP BY s.user_id
    ORDER BY score DESC
    LIMIT 20
  `,[],(err,rows)=>{
    if(err) return res.status(500).json({ error:"Unable to load leaderboard" });
    res.json(rows);
  });
});

app.get("/api/leaderboard/weekly",(req,res)=>{
  db.all(`
    SELECT u.username, MAX(s.score) score
    FROM scores s
    JOIN users u ON s.user_id=u.id
    WHERE s.created_at >= datetime('now','-7 day')
    GROUP BY s.user_id
    ORDER BY score DESC
    LIMIT 20
  `,[],(err,rows)=>{
    if(err) return res.status(500).json({ error:"Unable to load weekly leaderboard" });
    res.json(rows);
  });
});

app.get("/api/leaderboard/monthly",(req,res)=>{
  db.all(`
    SELECT u.username, MAX(s.score) score
    FROM scores s
    JOIN users u ON s.user_id=u.id
    WHERE s.created_at >= datetime('now','-30 day')
    GROUP BY s.user_id
    ORDER BY score DESC
    LIMIT 20
  `,[],(err,rows)=>{
    if(err) return res.status(500).json({ error:"Unable to load monthly leaderboard" });
    res.json(rows);
  });
});

app.get("/api/leaderboard/daily",(req,res)=>{
  db.all(`
    SELECT u.username, MAX(s.score) score
    FROM scores s
    JOIN users u ON s.user_id=u.id
    WHERE date(s.created_at)=date('now')
    GROUP BY s.user_id
    ORDER BY score DESC
    LIMIT 20
  `,[],(err,rows)=>{
    if(err) return res.status(500).json({ error:"Unable to load daily leaderboard" });
    res.json(rows);
  });
});

app.get("/api/leaderboard/me", auth, (req,res)=>{
  db.get(`
    SELECT highest_score AS score, highest_level AS level, games_played
    FROM users
    WHERE id = ?
  `,[req.user.id],(err,row)=>{
    if(err) return res.status(500).json({ error:"Unable to load personal best" });
    res.json({ score: row?.score || 0, level: row?.level || 0, games_played: row?.games_played || 0 });
  });
});

const players = {};

io.on("connection",(socket)=>{
  console.log("Player Connected:",socket.id);

  players[socket.id] = {
    id:socket.id,
    x:100,
    y:100
  };

  io.emit("players",players);

  socket.on("move",(data)=>{
    if(
      players[socket.id] &&
      data &&
      Number.isFinite(data.x) &&
      Number.isFinite(data.y)
    ){
      players[socket.id].x = data.x;
      players[socket.id].y = data.y;
      io.emit("players",players);
    }
  });

  socket.on("disconnect",()=>{
    delete players[socket.id];
    io.emit("players",players);
    console.log("Disconnected:",socket.id);
  });
});

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({ error:"Server Error" });
});

server.listen(PORT,()=>{
  console.log(`Server running on ${PORT}`);
});
