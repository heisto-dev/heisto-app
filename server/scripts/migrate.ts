import 'dotenv/config';
import { createPgDb, migrate } from '../src/db.js';

const db = createPgDb(process.env.DATABASE_URL!);
await migrate(db);
await db.end();
console.log('Database migrated');
