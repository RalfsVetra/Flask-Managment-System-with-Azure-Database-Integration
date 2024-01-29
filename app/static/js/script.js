let ajax_form = document.querySelector('.ajax-form');

ajax_form.onsubmit = e => {
    e.preventDefault();
    process_form(ajax_form);
};

const process_form = (ajax_form) => {
    let form_data = new FormData(ajax_form);

    fetch(ajax_form.action, { method: 'POST', body: form_data }).then(response => response.text()).then(result => {
        if (result.toLowerCase().includes('success')) {
            window.location.href = 'admin';
        } else if (result.includes('tfa:')) {
            window.location.href = result.replace('tfa: ', '');
        } else if (result.toLowerCase().includes('autologin')) {
            window.location.href = 'home';
        } else {
            document.querySelector('.msg').innerHTML = result;
        }
    });
};