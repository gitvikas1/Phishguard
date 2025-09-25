// Get references
const form = document.getElementById('analyze-form');
const resultDiv = document.getElementById('result');
const detailsDiv = document.getElementById('details');
const tableBody = document.getElementById('history-body'); // tbody for history table

// Handle form submission
if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    resultDiv.className = 'result hidden';
    detailsDiv.className = 'details hidden';
    resultDiv.textContent = 'Analyzing...';

    const formData = new FormData(form);

    try {
      const res = await fetch('/analyze', { method: 'POST', body: formData });
      const data = await res.json();

      if (!data.ok) throw new Error(data.message || 'Analysis failed');

      // Update result card
      resultDiv.classList.remove('hidden');
      resultDiv.classList.add('result', data.verdict === 'safe' ? 'safe' : 'phishing');
      resultDiv.textContent = `${data.message}${data.reason ? ` (reason: ${data.reason}, score: ${data.score ?? ''})` : ''}`;

      // Show details
      detailsDiv.classList.remove('hidden');
      detailsDiv.innerHTML = '<pre>' + JSON.stringify(data.features, null, 2) + '</pre>';

      // Add row to history table
      if (tableBody) {
        const tr = document.createElement('tr');
        tr.className = data.verdict === 'safe' ? 'safe' : 'phishing';
        tr.innerHTML = `
          <td class="url">${data.url}</td>
          <td>${data.verdict}</td>
          <td>${data.reason || ''}</td>
          <td>${data.score ?? ''}</td>
          <td>${new Date().toUTCString()}</td>
        `;
        tableBody.prepend(tr); // Add newest on top
      }

    } catch (err) {
      resultDiv.classList.remove('hidden');
      resultDiv.classList.add('result', 'phishing');
      resultDiv.textContent = 'Error: ' + err.message;
    }
  });
}

// Ripple effect for all buttons
document.querySelectorAll('button').forEach(button => {
  button.addEventListener('click', function(e) {
    const ripple = document.createElement('span');
    ripple.classList.add('ripple');

    // Position ripple at click location
    const rect = button.getBoundingClientRect();
    ripple.style.left = `${e.clientX - rect.left}px`;
    ripple.style.top = `${e.clientY - rect.top}px`;

    button.appendChild(ripple);

    // Remove ripple after animation
    setTimeout(() => ripple.remove(), 600);
  });
});
