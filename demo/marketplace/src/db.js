'use strict';

const { MongoClient } = require('mongodb');
const config = require('./config');

let client;
let database;

async function connect() {
  if (database) return database;

  client = new MongoClient(config.mongo.url, {
    serverSelectionTimeoutMS: 10000,
  });

  // Mongo may still be starting when the app boots, so retry for a while.
  const deadline = Date.now() + 60000;
  for (;;) {
    try {
      await client.connect();
      break;
    } catch (err) {
      if (Date.now() > deadline) throw err;
      console.log('[db] waiting for mongo…');
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  database = client.db(config.mongo.db);

  await database
    .collection('agents')
    .createIndexes([
      { key: { softwareId: 1 }, unique: true },
      { key: { status: 1 } },
      { key: { createdAt: -1 } },
    ]);
  await database.collection('cache').createIndex({ key: 1 }, { unique: true });

  console.log(`[db] connected to ${config.mongo.db}`);
  return database;
}

const db = () => {
  if (!database) throw new Error('database not connected');
  return database;
};

const agents = () => db().collection('agents');
const cache = () => db().collection('cache');

async function close() {
  if (client) await client.close();
  database = undefined;
}

module.exports = { connect, db, agents, cache, close };
