function checkAuth() {
    if (!localStorage.getItem('token')) {
      window.location.href = '/pages/auth/login.html';
    }
  }
  
  function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('userType');
    localStorage.removeItem('userId');
    window.location.href = '/pages/auth/login.html';
  }
  
  function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }
  
  function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }
  
  function validateForm(form) {
    const inputs = form.querySelectorAll('input[required]');
    for (const input of inputs) {
      if (!input.value.trim()) {
        showError(form, `${input.name} is required`);
        return false;
      }
    }
    return true;
  }