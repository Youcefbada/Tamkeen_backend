document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.querySelector('#login-form');
    const signupForms = document.querySelectorAll('.signup-form');
  
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = loginForm.querySelector('#email').value;
        const password = loginForm.querySelector('#password').value;
        const userType = loginForm.querySelector('#user-type').value;
  
        try {
          const endpoint = userType === 'trainer' ? '/logintrainers' : `/login${userType}s`;
          const data = await apiRequest(endpoint, 'POST', { email, password }, false);
          localStorage.setItem('token', data.token);
          localStorage.setItem('userType', userType);
          localStorage.setItem('userId', data.user.id);
          window.location.href = `/pages/${userType}/dashboard.html`;
        } catch (error) {
          showError(loginForm, error.message);
        }
      });
    }
  
    signupForms.forEach(form => {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        const data = Object.fromEntries(formData);
        const userType = form.dataset.userType;
  
        try {
          const endpoint = userType === 'trainer' ? '/signuptrainers' : `/signup${userType}s`;
          const response = await apiRequest(endpoint, 'POST', data, false);
          alert(response.message);
          window.location.href = '/pages/auth/login.html';
        } catch (error) {
          showError(form, error.message);
        }
      });
    });
  });
  
  function showError(form, message) {
    const errorDiv = form.querySelector('.error');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
  }