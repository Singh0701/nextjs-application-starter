import { ApolloError } from 'apollo-server';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Mock user store (replace with DB in real app)
const users: any[] = [];

export async function registerUser(name: string, email: string, password: string) {
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    throw new ApolloError('User already exists');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, name, email, password: hashedPassword };
  users.push(newUser);
  const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '7d' });
  return { token, user: newUser };
}

export async function loginUser(email: string, password: string) {
  const user = users.find(u => u.email === email);
  if (!user) {
    throw new ApolloError('Invalid credentials');
  }
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    throw new ApolloError('Invalid credentials');
  }
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  return { token, user };
}
