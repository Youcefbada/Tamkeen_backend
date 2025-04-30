const API_BASE_URL = 'http://localhost:3000'; // Update with your backend URL

async function apiRequest(endpoint, method = 'GET', body = null, includeToken = true) {
  const headers = {
    'Content-Type': 'application/json',
  };

  if (includeToken) {
    const token = localStorage.getItem('token');
    if (token) {
      headers['Authorization'] = token;
    }
  }

  const config = {
    method,
    headers,
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Request failed');
    }
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
}