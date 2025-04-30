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