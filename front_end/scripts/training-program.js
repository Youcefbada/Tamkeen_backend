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