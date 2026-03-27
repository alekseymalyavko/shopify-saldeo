(() => {
  const checkbox = document.getElementById('kupuje-na-firme');
  const block = document.getElementById('nip-block');
  const nipInput = document.getElementById('cart-nip');
  const nipError = document.getElementById('nip-error');
  const checkoutBtn = document.getElementById('checkout');

  if (!checkbox || !block || !nipInput) return;

  function toggle() {
    if (checkbox.checked) {
      block.removeAttribute('hidden');
    } else {
      block.setAttribute('hidden', '');
      nipInput.value = '';
      if (nipError) nipError.setAttribute('hidden', '');
    }
  }

  toggle();
  checkbox.addEventListener('change', toggle);

  if (checkoutBtn && nipError) {
    checkoutBtn.addEventListener('click', (e) => {
      if (checkbox.checked && !nipInput.value.trim()) {
        e.preventDefault();
        nipError.removeAttribute('hidden');
        nipInput.focus();
      }
    });
  }
})();
