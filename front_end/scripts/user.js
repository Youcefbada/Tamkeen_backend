document.addEventListener('DOMContentLoaded', () => {
    const profileForm = document.querySelector('#profile-form');
    const interestsList = document.querySelector('#interests-list');
  
    if (profileForm) {
      loadUserProfile();
      profileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(profileForm);
        const data = Object.fromEntries(formData);
  
        try {
          await apiRequest(`/users/${localStorage.getItem('userId')}`, 'PUT', data);
          alert('Profile updated successfully');
        } catch (error) {
          showError(profileForm, error.message);
        }
      });
    }
  
    if (interestsList) {
      loadUserInterests();
    }
  });
  
  async function loadUserProfile() {
    try {
      const user = await apiRequest(`/users/${localStorage.getItem('userId')}`);
      const inputs = document.querySelectorAll('#profile-form input');
      inputs.forEach(input => {
        if (user[input.name]) {
          input.value = user[input.name];
        }
      });
    } catch (error) {
      console.error('Error loading profile:', error);
    }
  }
  
  async function loadUserInterests() {
    try {
      const interests = await apiRequest(`/users/${localStorage.getItem('userId')}/interests`);
      const list = document.querySelector('#interests-list');
      list.innerHTML = interests.map(interest => `
        <li>
          ${interest.name}
          <button onclick="deleteInterest(${interest.id})">Delete</button>
        </li>
      `).join('');
    } catch (error) {
      console.error('Error loading interests:', error);
    }
  }
  
  async function deleteInterest(id) {
    if (confirm('Are you sure you want to delete this interest?')) {
      try {
        await apiRequest(`/interests/${id}`, 'DELETE');
        loadUserInterests();
      } catch (error) {
        alert(error.message);
      }
    }
  }