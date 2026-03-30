const fs = require('fs');
const path = require('path');

// In-memory storage - SMALL limit to prevent memory crashes
const packets = [];
const MAX_MEMORY_PACKETS = 500;  // Changed from 5000 to 500 - small working set only
const MAX_PACKET_AGE_MS = 3600000; // Keep stored packets for 1 hour
let lastCleanupTime = Date.now();
const CLEANUP_INTERVAL = 60000; // Run cleanup every minute

// Local storage configuration
const PACKETS_DIR = path.join(__dirname, '../packets-storage');
const PACKETS_INDEX = path.join(PACKETS_DIR, 'packets-index.json');

// Filter configuration - exclude packets from server services
const SERVER_PORTS = [3000, 5050]; // Frontend: 3000, Backend: 5050
const SERVER_IP = process.env.SERVER_IP || '192.168.4.115'; // Can be overridden via environment variable

// Ensure storage directory exists
if (!fs.existsSync(PACKETS_DIR)) {
    fs.mkdirSync(PACKETS_DIR, { recursive: true });
    console.log(`[packetStore] Created packets storage directory: ${PACKETS_DIR}`);
}

// Initialize index if it doesn't exist
if (!fs.existsSync(PACKETS_INDEX)) {
    fs.writeFileSync(PACKETS_INDEX, JSON.stringify({ files: [], totalCount: 0 }));
}

// Helper function to check if packet should be filtered (excluded)
function shouldFilterPacket(packet) {
    if (!packet) return true;
    
    // Check if source port is a server port
    if (SERVER_PORTS.includes(packet.sourcePort)) {
        return true;
    }
    
    // Check if destination port is a server port
    if (SERVER_PORTS.includes(packet.destPort)) {
        return true;
    }
    
    return false;
}

function addPacket(packet) {
    // Filter out packets from server services (ports 3000 and 5050)
    // if (shouldFilterPacket(packet)) {
    //     return; // Skip this packet
    // }
    
    // Push to memory
    packets.push(packet);
    
    // If memory exceeds limit, save excess to local storage
    if (packets.length > MAX_MEMORY_PACKETS) {
        saveExcessPacketsToStorage();
    }
    
    // Cleanup expired packets periodically
    const now = Date.now();
    if (now - lastCleanupTime > CLEANUP_INTERVAL) {
        cleanupExpiredPackets();
        lastCleanupTime = now;
    }
}

function saveExcessPacketsToStorage() {
    // Keep only the most recent MAX_MEMORY_PACKETS in memory
    const toSave = packets.splice(0, packets.length - MAX_MEMORY_PACKETS);
    
    if (toSave.length === 0) return;
    
    try {
        // Create a file for this batch of packets with timestamp
        const filename = `packets-${Date.now()}.json`;
        const filepath = path.join(PACKETS_DIR, filename);
        
        // Write packets to file
        fs.writeFileSync(filepath, JSON.stringify({
            packets: toSave,
            savedAt: new Date().toISOString(),
            count: toSave.length
        }, null, 2));
        
        // Update index
        updatePacketsIndex(filename, toSave.length);
        
        console.log(`[packetStore] Saved ${toSave.length} packets to local storage: ${filename}`);
    } catch (error) {
        console.error('[packetStore] Error saving packets to storage:', error.message);
        // If save fails, keep packets in memory (graceful degradation)
        packets.unshift(...toSave);
    }
}

function updatePacketsIndex(filename, count) {
    try {
        const index = JSON.parse(fs.readFileSync(PACKETS_INDEX, 'utf8'));
        index.files.push({
            name: filename,
            count: count,
            savedAt: new Date().toISOString()
        });
        index.totalCount += count;
        fs.writeFileSync(PACKETS_INDEX, JSON.stringify(index, null, 2));
    } catch (error) {
        console.error('[packetStore] Error updating packets index:', error.message);
    }
}

function cleanupExpiredPackets() {
    const now = Date.now();
    let removed = 0;
    
    // Cleanup memory packets
    while (packets.length > 0) {
        const packetTime = new Date(packets[0].timestamp).getTime();
        if (now - packetTime > MAX_PACKET_AGE_MS) {
            packets.shift();
            removed++;
        } else {
            break;
        }
    }
    
    // Cleanup storage files older than 1 hour
    try {
        const index = JSON.parse(fs.readFileSync(PACKETS_INDEX, 'utf8'));
        const filesToKeep = [];
        let filesRemoved = 0;
        
        for (const file of index.files) {
            const fileTime = new Date(file.savedAt).getTime();
            if (now - fileTime > MAX_PACKET_AGE_MS) {
                // Delete the file
                const filepath = path.join(PACKETS_DIR, file.name);
                if (fs.existsSync(filepath)) {
                    fs.unlinkSync(filepath);
                    filesRemoved++;
                }
            } else {
                filesToKeep.push(file);
            }
        }
        
        if (filesRemoved > 0) {
            index.files = filesToKeep;
            fs.writeFileSync(PACKETS_INDEX, JSON.stringify(index, null, 2));
            console.log(`[packetStore] Cleaned up ${filesRemoved} expired storage files (${removed} memory packets)`);
        }
    } catch (error) {
        console.error('[packetStore] Error during storage cleanup:', error.message);
    }
}

function getPackets() {
    // Return only in-memory packets
    return packets;
}

function getRecentPackets(limit = 500) {
    // Return only the most recent N packets from memory
    return packets.slice(-limit);
}

function getPacketCount() {
    return packets.length;
}

function getStoragePacketCount() {
    // Get total count from both memory and storage
    try {
        const index = JSON.parse(fs.readFileSync(PACKETS_INDEX, 'utf8'));
        return {
            memoryCount: packets.length,
            storageCount: index.totalCount,
            totalCount: packets.length + index.totalCount,
            files: index.files.length
        };
    } catch (error) {
        return {
            memoryCount: packets.length,
            storageCount: 0,
            totalCount: packets.length,
            files: 0
        };
    }
}

function getAllPacketsFromStorage() {
    // Read all packets from storage files (for full analysis)
    const allPackets = [];
    
    try {
        const index = JSON.parse(fs.readFileSync(PACKETS_INDEX, 'utf8'));
        
        for (const file of index.files) {
            const filepath = path.join(PACKETS_DIR, file.name);
            if (fs.existsSync(filepath)) {
                const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
                allPackets.push(...data.packets);
            }
        }
    } catch (error) {
        console.error('[packetStore] Error reading storage packets:', error.message);
    }
    
    // Add memory packets at the end (most recent)
    allPackets.push(...packets);
    
    return allPackets;
}

function clearStorage() {
    // Clear all storage files and reset index
    try {
        const index = JSON.parse(fs.readFileSync(PACKETS_INDEX, 'utf8'));
        
        for (const file of index.files) {
            const filepath = path.join(PACKETS_DIR, file.name);
            if (fs.existsSync(filepath)) {
                fs.unlinkSync(filepath);
            }
        }
        
        fs.writeFileSync(PACKETS_INDEX, JSON.stringify({ files: [], totalCount: 0 }));
        console.log('[packetStore] Cleared all packet storage');
    } catch (error) {
        console.error('[packetStore] Error clearing storage:', error.message);
    }
}

module.exports = { 
    addPacket, 
    getPackets, 
    getRecentPackets, 
    getPacketCount, 
    cleanupExpiredPackets,
    getStoragePacketCount,
    getAllPacketsFromStorage,
    clearStorage
}
