import mongoose from "mongoose";

const connectDB = async () => {
  try {
    console.log('Attempting MongoDB connection...');
    console.log('MONGO_URI exists:', !!process.env.MONGO_URI);
    
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000, // 10 second timeout
    });
    console.log(`MongoDB Connected Successfully to: ${conn.connection.host}`);
  } catch (error) {
    console.error(`MongoDB Connection Error: ${error.message}`);
    console.error('Full error:', error);
    // Don't exit in production, let health checks fail instead
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
};

export default connectDB;
