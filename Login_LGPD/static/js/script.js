document.addEventListener('DOMContentLoaded', function () {
    document.body.classList.add('fade-in');

    const flashMessages = document.querySelectorAll('.flash-messages .flash');
    flashMessages.forEach(function (message) {
        setTimeout(function () {
            message.classList.add('fade-out');

            setTimeout(function () {
                if (message.parentElement) {
                    message.parentElement.removeChild(message);
                }
            }, 500);
        }, 5000);
    });

    const fadeLink = document.querySelector('.fade-link');
    if (fadeLink) {
        fadeLink.addEventListener('click', (e) => {
            e.preventDefault();
            document.body.classList.remove("fade-in");
            document.body.classList.add("fade-out");

            setTimeout(() => {
                window.location.href = fadeLink.href;
            }, 500);
        });
    }
});
