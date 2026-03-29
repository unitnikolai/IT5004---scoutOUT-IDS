const packets = [];
const MAX_PACKETS = 10000; // Reduced for better memory efficiency
const MAX_PACKET_AGE_MS = 3600000; // Keep packets for 1 hour

function addPacket(packet){
    packets.unshift(packet);
    
    // Remove packets over limit
    if (packets.length > MAX_PACKETS){
        packets.pop();
    }
    
    // Remove packets older than max age
    const now = Date.now();
    let lastValidIndex = packets.length - 1;
    for (let i = 0; i < packets.length; i++) {
        const packetTime = new Date(packets[i].timestamp).getTime();
        if (now - packetTime > MAX_PACKET_AGE_MS) {
            lastValidIndex = i - 1;
            break;
        }
    }
    
    if (lastValidIndex < packets.length - 1) {
        packets.splice(lastValidIndex + 1);
    }
}

function getPackets(){
    return packets;
}

module.exports = { addPacket, getPackets }