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