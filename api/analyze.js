import { handleApiRequest } from '../backend/app/handler.js';

export default async function handler(req, res) {
  return handleApiRequest(req, res);
}
