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