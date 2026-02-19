import mongoose from 'mongoose';

class Database {
  constructor() {
    this.connection = null;
  }

  async connect() {
    try {
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/sentinelapi';
      
      this.connection = await mongoose.connect(mongoUri);

      console.log(`MongoDB connected: ${this.connection.connection.host}`);
      
      // Handle connection events
      mongoose.connection.on('error', (err) => {
        console.error('MongoDB connection error:', err);
      });

      mongoose.connection.on('disconnected', () => {
        console.log('MongoDB disconnected');
      });

      return this.connection;
    } catch (error) {
      console.error('Database connection failed:', error);
      console.log('Continuing without database connection...');
      return null;
    }
  }

  async disconnect() {
    if (this.connection) {
      await mongoose.disconnect();
      console.log('MongoDB disconnected');
    }
  }

  getConnection() {
    return this.connection;
  }
}

export default new Database();