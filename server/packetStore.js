const packets = [];
const MAX_PACKETS = 10000;

function addPacket(packet){
    packets.unshift(packet);
    if (packets.length > MAX_PACKETS){
        packets.pop()
    }
}

function getPackets(){
    return packets;
}

module.exports = { addPacket, getPackets }