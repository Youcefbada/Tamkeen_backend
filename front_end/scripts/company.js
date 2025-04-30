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