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