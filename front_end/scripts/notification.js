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