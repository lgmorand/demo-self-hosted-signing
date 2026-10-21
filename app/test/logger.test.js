'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Logger } = require('../lib/logger');

test('keeps a bounded buffer, writes JSON lines to the sink and supports filters', () => {
  const lines = [];
  const logger = new Logger({ capacity: 3, sink: (line) => lines.push(line) });
  logger.log('a');
  logger.log('b', { x: 1 });
  logger.log('a');
  logger.log('c');

  assert.equal(lines.length, 4);
  assert.equal(JSON.parse(lines[1]).x, 1);
  assert.deepEqual(logger.entries().map((entry) => entry.seq), [2, 3, 4], 'oldest entries are dropped');
  assert.deepEqual(logger.entries({ event: 'a,c' }).map((entry) => entry.seq), [3, 4]);
  assert.deepEqual(logger.entries({ after: 3 }).map((entry) => entry.seq), [4]);
  assert.deepEqual(logger.entries({ limit: 1 }).map((entry) => entry.seq), [4]);
});
