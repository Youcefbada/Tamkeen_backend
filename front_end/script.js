/* api.js */
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

/* auth.js */
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

/* user.js */
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

/* company.js */
document.addEventListener('DOMContentLoaded', () => {
  const internshipList = document.querySelector('#internship-list');
  const internshipForm = document.querySelector('#internship-form');

  if (internshipList) {
    loadCompanyInternships();
  }

  if (internshipForm) {
    internshipForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(internshipForm);
      const data = Object.fromEntries(formData);
      data.company_id = localStorage.getItem('userId');

      try {
        await apiRequest('/internships', 'POST', data);
        alert('Internship created successfully');
        window.location.href = '/pages/company/internships.html';
      } catch (error) {
        showError(internshipForm, error.message);
      }
    });
  }
});

async function loadCompanyInternships() {
  try {
    const internships = await apiRequest(`/companies/${localStorage.getItem('userId')}/internships`);
    const list = document.querySelector('#internship-list');
    list.innerHTML = internships.map(internship => `
      <div class="internship-item">
        <h3>${internship.title}</h3>
        <p>${internship.description}</p>
        <button onclick="editInternship(${internship.id})">Edit</button>
        <button onclick="deleteInternship(${internship.id})">Delete</button>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading internships:', error);
  }
}

async function editInternship(id) {
  window.location.href = `/pages/company/internships.html?edit=${id}`;
}

async function deleteInternship(id) {
  if (confirm('Are you sure you want to delete this internship?')) {
    try {
      await apiRequest(`/internships/${id}`, 'DELETE');
      loadCompanyInternships();
    } catch (error) {
      alert(error.message);
    }
  }
}

/* training-center.js */
document.addEventListener('DOMContentLoaded', () => {
  const programList = document.querySelector('#training-program-list');
  const programForm = document.querySelector('#training-program-form');
  const trainerList = document.querySelector('#trainer-list');

  if (programList) {
    loadTrainingPrograms();
  }

  if (programForm) {
    programForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(programForm);
      const data = Object.fromEntries(formData);
      data.center_id = localStorage.getItem('userId');

      try {
        await apiRequest('/training_programs', 'POST', data);
        alert('Training program created successfully');
        window.location.href = '/pages/training-center/training-programs.html';
      } catch (error) {
        showError(programForm, error.message);
      }
    });
  }

  if (trainerList) {
    loadProgramTrainers();
  }
});

async function loadTrainingPrograms() {
  try {
    const programs = await apiRequest(`/training_centers/${localStorage.getItem('userId')}/programs`);
    const list = document.querySelector('#training-program-list');
    list.innerHTML = programs.map(program => `
      <div class="training-program-item">
        <h3>${program.title}</h3>
        <p>${program.description}</p>
        <button onclick="editProgram(${program.id})">Edit</button>
        <button onclick="deleteProgram(${program.id})">Delete</button>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading programs:', error);
  }
}

async function loadProgramTrainers() {
  try {
    const programId = new URLSearchParams(window.location.search).get('programId');
    const trainers = await apiRequest(`/training_programs/${programId}/trainers`);
    const list = document.querySelector('#trainer-list');
    list.innerHTML = trainers.map(trainer => `
      <tr>
        <td>${trainer.first_name} ${trainer.last_name}</td>
        <td>${trainer.email}</td>
        <td><button onclick="removeTrainer(${trainer.id}, ${programId})">Remove</button></td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading trainers:', error);
  }
}

async function editProgram(id) {
  window.location.href = `/pages/training-center/training-programs.html?edit=${id}`;
}

async function deleteProgram(id) {
  if (confirm('Are you sure you want to delete this training program?')) {
    try {
      await apiRequest(`/training_programs/${id}`, 'DELETE');
      loadTrainingPrograms();
    } catch (error) {
      alert(error.message);
    }
  }
}

async function removeTrainer(trainerId, programId) {
  if (confirm('Are you sure you want to remove this trainer?')) {
    try {
      await apiRequest(`/training_programs/${programId}/trainers/${trainerId}`, 'DELETE');
      loadProgramTrainers();
    } catch (error) {
      alert(error.message);
    }
  }
}

/* trainer.js */
document.addEventListener('DOMContentLoaded', () => {
  const programList = document.querySelector('#training-program-list');

  if (programList) {
    loadTrainerPrograms();
  }
});

async function loadTrainerPrograms() {
  try {
    const trainerId = localStorage.getItem('userId');
    const programs = await apiRequest(`/trainers/${trainerId}/training_programs`);
    const list = document.querySelector('#training-program-list');
    list.innerHTML = programs.map(program => `
      <div class="training-program-item">
        <h3>${program.title}</h3>
        <p>${program.description}</p>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading programs:', error);
  }
}

/* internship.js */
document.addEventListener('DOMContentLoaded', () => {
  const internshipList = document.querySelector('#internship-list');
  const applyForm = document.querySelector('#apply-internship-form');

  if (internshipList) {
    loadInternships();
  }

  if (applyForm) {
    applyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(applyForm);
      const data = Object.fromEntries(formData);
      data.internship_id = new URLSearchParams(window.location.search).get('internshipId');

      try {
        await apiRequest('/internship_applications', 'POST', data);
        alert('Application submitted successfully');
        window.location.href = '/pages/user/internship-applications.html';
      } catch (error) {
        showError(applyForm, error.message);
      }
    });
  }
});

async function loadInternships() {
  try {
    const internships = await apiRequest('/internships');
    const list = document.querySelector('#internship-list');
    list.innerHTML = internships.map(internship => `
      <div class="internship-item">
        <h3>${internship.title}</h3>
        <p>${internship.description}</p>
        <button onclick="applyInternship(${internship.id})">Apply</button>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading internships:', error);
  }
}

function applyInternship(id) {
  window.location.href = `/pages/user/internship-applications.html?apply=${id}`;
}

/* training-program.js */
document.addEventListener('DOMContentLoaded', () => {
  const programList = document.querySelector('#training-program-list');
  const applyForm = document.querySelector('#apply-program-form');

  if (programList) {
    loadTrainingPrograms();
  }

  if (applyForm) {
    applyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(applyForm);
      const data = Object.fromEntries(formData);
      data.training_program_id = new URLSearchParams(window.location.search).get('programId');

      try {
        await apiRequest('/program_applications', 'POST', data);
        alert('Application submitted successfully');
        window.location.href = '/pages/user/program-applications.html';
      } catch (error) {
        showError(applyForm, error.message);
      }
    });
  }
});

async function loadTrainingPrograms() {
  try {
    const programs = await apiRequest('/training_programs');
    const list = document.querySelector('#training-program-list');
    list.innerHTML = programs.map(program => `
      <div class="training-program-item">
        <h3>${program.title}</h3>
        <p>${program.description}</p>
        <button onclick="applyProgram(${program.id})">Apply</button>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading programs:', error);
  }
}

function applyProgram(id) {
  window.location.href = `/pages/user/program-applications.html?apply=${id}`;
}

/* application.js */
document.addEventListener('DOMContentLoaded', () => {
  const internshipApplicationList = document.querySelector('#internship-application-list');
  const programApplicationList = document.querySelector('#program-application-list');

  if (internshipApplicationList) {
    loadInternshipApplications();
  }

  if (programApplicationList) {
    loadProgramApplications();
  }
});

async function loadInternshipApplications() {
  try {
    const userId = localStorage.getItem('userId');
    const applications = await apiRequest(`/users/${userId}/internship_applications`);
    const list = document.querySelector('#internship-application-list');
    list.innerHTML = applications.map(app => `
      <tr>
        <td>${app.internship_id}</td>
        <td>${app.education_level}</td>
        <td class="status-${app.status.toLowerCase()}">${app.status}</td>
        <td>
          <button onclick="updateApplication(${app.id}, 'internship')">Edit</button>
          <button onclick="deleteApplication(${app.id}, 'internship')">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading internship applications:', error);
  }
}

async function loadProgramApplications() {
  try {
    const userId = localStorage.getItem('userId');
    const applications = await apiRequest(`/users/${userId}/program_applications`);
    const list = document.querySelector('#program-application-list');
    list.innerHTML = applications.map(app => `
      <tr>
        <td>${app.training_program_id}</td>
        <td>${app.education_level}</td>
        <td class="status-${app.status.toLowerCase()}">${app.status}</td>
        <td>
          <button onclick="updateApplication(${app.id}, 'program')">Edit</button>
          <button onclick="deleteApplication(${app.id}, 'program')">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading program applications:', error);
  }
}

async function updateApplication(id, type) {
  window.location.href = `/pages/user/${type}-applications.html?edit=${id}`;
}

async function deleteApplication(id, type) {
  if (confirm('Are you sure you want to delete this application?')) {
    try {
      await apiRequest(`/${type}_applications/${id}`, 'DELETE');
      type === 'internship' ? loadInternshipApplications() : loadProgramApplications();
    } catch (error) {
      alert(error.message);
    }
  }
}

/* notification.js */
document.addEventListener('DOMContentLoaded', () => {
  const notificationList = document.querySelector('#notification-list');

  if (notificationList) {
    loadNotifications();
  }
});

async function loadNotifications() {
  try {
    const userId = localStorage.getItem('userId');
    const notifications = await apiRequest(`/users/${userId}/notifications`);
    const list = document.querySelector('#notification-list');
    list.innerHTML = notifications.map(notification => `
      <div class="notification-item ${notification.is_read ? '' : 'unread'}">
        <p>${notification.content}</p>
        <button onclick="markAsRead(${notification.id})">${notification.is_read ? 'Mark Unread' : 'Mark Read'}</button>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading notifications:', error);
  }
}

async function markAsRead(id) {
  try {
    const notification = await apiRequest(`/notifications/${id}`);
    await apiRequest(`/notifications/${id}`, 'PUT', { 
      user_id: notification.user_id, 
      content: notification.content, 
      is_read: !notification.is_read 
    });
    loadNotifications();
  } catch (error) {
    alert(error.message);
  }
}

/* interest.js */
document.addEventListener('DOMContentLoaded', () => {
  const interestForm = document.querySelector('#interest-form');

  if (interestForm) {
    interestForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = interestForm.querySelector('#interest-name').value;

      try {
        await apiRequest('/interests', 'POST', { name });
        alert('Interest added successfully');
        loadUserInterests();
        interestForm.reset();
      } catch (error) {
        showError(interestForm, error.message);
      }
    });
  }
});

/* admin.js */
document.addEventListener('DOMContentLoaded', () => {
  const userList = document.querySelector('#user-list');
  const companyList = document.querySelector('#company-list');
  const centerList = document.querySelector('#training-center-list');
  const trainerList = document.querySelector('#trainer-list');
  const internshipList = document.querySelector('#admin-internship-list');
  const programList = document.querySelector('#admin-program-list');
  const notificationForm = document.querySelector('#notification-form');

  if (userList) loadAdminUsers();
  if (companyList) loadAdminCompanies();
  if (centerList) loadAdminTrainingCenters();
  if (trainerList) loadAdminTrainers();
  if (internshipList) loadAdminInternships();
  if (programList) loadAdminPrograms();
  if (notificationForm) {
    notificationForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(notificationForm);
      const data = Object.fromEntries(formData);

      try {
        await apiRequest('/notifications', 'POST', data);
        alert('Notification sent successfully');
        notificationForm.reset();
      } catch (error) {
        showError(notificationForm, error.message);
      }
    });
  }
});

async function loadAdminUsers() {
  try {
    const users = await apiRequest('/users');
    const list = document.querySelector('#user-list');
    list.innerHTML = users.map(user => `
      <tr>
        <td>${user.first_name} ${user.last_name}</td>
        <td>${user.email}</td>
        <td><button onclick="deleteUser(${user.id})">Delete</button></td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading users:', error);
  }
}

async function loadAdminCompanies() {
  try {
    const companies = await apiRequest('/companies');
    const list = document.querySelector('#company-list');
    list.innerHTML = companies.map(company => `
      <tr>
        <td>${company.name}</td>
        <td>${company.email}</td>
        <td><button onclick="deleteCompany(${company.id})">Delete</button></td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading companies:', error);
  }
}

async function loadAdminTrainingCenters() {
  try {
    const centers = await apiRequest('/training_centers');
    const list = document.querySelector('#training-center-list');
    list.innerHTML = centers.map(center => `
      <tr>
        <td>${center.name}</td>
        <td>${center.email}</td>
        <td><button onclick="deleteTrainingCenter(${center.id})">Delete</button></td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading training centers:', error);
  }
}

async function loadAdminTrainers() {
  try {
    const trainers = await apiRequest('/trainers');
    const list = document.querySelector('#trainer-list');
    list.innerHTML = trainers.map(trainer => `
      <tr>
        <td>${trainer.first_name} ${trainer.last_name}</td>
        <td>${trainer.email}</td>
        <td><button onclick="deleteTrainer(${trainer.id})">Delete</button></td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading trainers:', error);
  }
}

async function loadAdminInternships() {
  try {
    const internships = await apiRequest('/internships');
    const list = document.querySelector('#admin-internship-list');
    list.innerHTML = internships.map(internship => `
      <tr>
        <td>${internship.title}</td>
        <td>${internship.company_id}</td>
        <td><button onclick="deleteInternship(${internship.id})">Delete</button></td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading internships:', error);
  }
}

async function loadAdminPrograms() {
  try {
    const programs = await apiRequest('/training_programs');
    const list = document.querySelector('#admin-program-list');
    list.innerHTML = programs.map(program => `
      <tr>
        <td>${program.title}</td>
        <td>${program.center_id}</td>
        <td><button onclick="deleteProgram(${program.id})">Delete</button></td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading programs:', error);
  }
}

async function deleteUser(id) {
  if (confirm('Are you sure you want to delete this user?')) {
    try {
      await apiRequest(`/users/${id}`, 'DELETE');
      loadAdminUsers();
    } catch (error) {
      alert(error.message);
    }
  }
}

async function deleteCompany(id) {
  if (confirm('Are you sure you want to delete this company?')) {
    try {
      await apiRequest(`/companies/${id}`, 'DELETE');
      loadAdminCompanies();
    } catch (error) {
      alert(error.message);
    }
  }
}

async function deleteTrainingCenter(id) {
  if (confirm('Are you sure you want to delete this training center?')) {
    try {
      await apiRequest(`/training_centers/${id}`, 'DELETE');
      loadAdminTrainingCenters();
    } catch (error) {
      alert(error.message);
    }
  }
}

async function deleteTrainer(id) {
  if (confirm('Are you sure you want to delete this trainer?')) {
    try {
      await apiRequest(`/trainers/${id}`, 'DELETE');
      loadAdminTrainers();
    } catch (error) {
      alert(error.message);
    }
  }
}

/* utils.js */
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