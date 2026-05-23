const socket = io();
const remotePlayers = {};

socket.on("players",(players)=>{
    Object.assign(remotePlayers,players);
});
