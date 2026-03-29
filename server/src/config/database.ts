import mongoose from 'mongoose';
import { env } from './env.js';

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

export async function connectWithRetry(): Promise<void> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      await mongoose.connect(env.MONGO_URI);
      console.info(`[DB] Connected to MongoDB Atlas (attempt ${attempt})`);
      return;
    } catch (err) {
      const isLastAttempt = attempt === MAX_RETRIES;
      const delay = BASE_DELAY_MS * 2 ** (attempt - 1); // 1s, 2s, 4s

      if (isLastAttempt) {
        console.error(`[DB] Failed to connect after ${MAX_RETRIES} attempts. Exiting.`, err);
        process.exit(1);
      }

      console.warn(`[DB] Connection attempt ${attempt} failed. Retrying in ${delay}ms...`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}
