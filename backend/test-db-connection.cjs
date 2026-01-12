
const mongoose = require('mongoose');

const uri = "mongodb+srv://roshnibhoi506:roshnibhoi506@deal-direct.vwlhuto.mongodb.net/Deal-Direct?retryWrites=true&w=majority&appName=Deal-Direct";

console.log("🔄 Testing MongoDB Connection...");
console.log(`📡 URI: ${uri.split('@')[1]}`); // Log only domain part for privacy

mongoose.connect(uri)
    .then(() => {
        console.log("✅ SUCCESS! Connected to MongoDB Atlas.");
        console.log(`🗄️  Database Name: ${mongoose.connection.name}`);
        console.log(`🔌 Host: ${mongoose.connection.host}`);
        process.exit(0);
    })
    .catch(err => {
        console.error("❌ CONNECTION FAILED:");
        console.error(err.message);
        process.exit(1);
    });
