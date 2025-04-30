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