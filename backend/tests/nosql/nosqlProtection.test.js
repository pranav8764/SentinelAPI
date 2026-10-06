import express from 'express';
import request from 'supertest';
import nosql, { nosqlProtection, sanitizeMongoQuery, validateUserInput } from '../../src/middleware/nosqlProtection.js';

const makeApp = () => {
  const app = express();
  app.set('query parser', 'extended'); // Express 5 default is 'simple' (no nested objects)
  app.use(express.json());
  app.use(nosqlProtection());
  app.post('/login', (req, res) => res.json({ body: req.body }));
  app.get('/search', (req, res) => res.json({ query: req.query }));
  return app;
};

describe('nosqlProtection middleware (supertest, no DB)', () => {
  test('blocks $where with 403', async () => {
    const res = await request(makeApp()).post('/login').send({ $where: 'function(){return true}' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('NOSQL_INJECTION_DETECTED');
  });
  test('blocks nested $regex', async () => {
    const res = await request(makeApp()).post('/login').send({ user: { $regex: '.*' } });
    expect(res.status).toBe(403);
  });
  test('neutralises $ne operator (strips $) instead of passing it through', async () => {
    const res = await request(makeApp()).post('/login').send({ password: { $ne: null } });
    expect(res.status).toBe(200);
    expect(res.body.body.password).not.toHaveProperty('$ne');
  });
  test('benign body passes unchanged', async () => {
    const body = { username: 'alice', age: 30, tags: ['a', 'b'] };
    const res = await request(makeApp()).post('/login').send(body);
    expect(res.status).toBe(200);
    expect(res.body.body).toEqual(body);
  });
  test('benign query passes', async () => {
    const res = await request(makeApp()).get('/search?q=hello');
    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ q: 'hello' });
  });
});

const { validateQuery, sanitizeValue } = nosql;

describe('nosql helpers', () => {
  test('validateQuery flags dangerous operator and JS code; clean query has no issues', () => {
    expect(validateQuery({ $where: 'x' }).map(i => i.type)).toContain('dangerous_operator');
    expect(validateQuery({ a: 'function(){}' }).map(i => i.type)).toContain('javascript_code');
    expect(validateQuery({ name: 'bob' })).toEqual([]);
  });
  test('sanitizeMongoQuery throws on $where, accepts safe query', () => {
    expect(() => sanitizeMongoQuery({ $where: '1' })).toThrow();
    expect(sanitizeMongoQuery({ name: 'bob' })).toEqual({ name: 'bob' });
  });
  test('sanitizeValue strict removes operator strings', () => {
    expect(sanitizeValue('$ne')).toBe('');
  });
  test('validateUserInput', () => {
    expect(validateUserInput('a$ne', 'string')).toBe('ane');
    expect(validateUserInput('507f1f77bcf86cd799439011', 'objectId')).toBe('507f1f77bcf86cd799439011');
    expect(() => validateUserInput('{"$ne":1}', 'objectId')).toThrow();
    expect(() => validateUserInput('nope', 'email')).toThrow();
    expect(validateUserInput('A@B.co', 'email')).toBe('a@b.co');
  });
});

describe('nosqlProtection: query-string operators (Express 5 getter-only req.query)', () => {
  test('neutralises ?user[$ne]=x without throwing', async () => {
    const res = await request(makeApp()).get('/search?user[$ne]=x');
    expect(res.status).toBe(200);
    expect(res.body.query.user).not.toHaveProperty('$ne');
  });
  test('blocks ?q[$where]=1', async () => {
    const res = await request(makeApp()).get('/search?q[$where]=1');
    expect(res.status).toBe(403);
  });
});
