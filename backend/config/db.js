import mongoose from "mongoose";

const connectDB = async () => {
  try {
    console.log('Attempting MongoDB connection...');
    console.log('MONGO_URI exists:', !!process.env.MONGO_URI);
    
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000, // 10 second timeout
    });
    // Report which database this process is actually talking to.
    //
    // The host alone is not enough: one cluster can hold several databases, and
    // the failure worth catching is connecting to the right cluster and the
    // wrong database. Both values are read back from the live connection rather
    // than parsed out of MONGO_URI, so they describe what happened rather than
    // what was configured.
    //
    // Host, database and NODE_ENV only. Never the URI, credentials or query
    // parameters: this line is printed at every startup and ends up in logs.
    console.log(
      `MongoDB connected  host=${conn.connection.host}  ` +
      `database=${conn.connection.name}  NODE_ENV=${process.env.NODE_ENV || '(unset)'}`
    );
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
