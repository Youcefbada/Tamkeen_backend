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