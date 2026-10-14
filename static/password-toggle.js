// Adds an eye button to every password field that switches between hidden
// and visible text. Loaded by both layouts, so new forms get it for free.
(function () {
    const EYE =
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    const EYE_OFF =
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>' +
        '<path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>' +
        '<path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

    document.querySelectorAll('input[type="password"]').forEach((input) => {
        const wrap = document.createElement("span");
        wrap.className = "password-wrap";
        input.parentNode.insertBefore(wrap, input);
        wrap.appendChild(input);
        // The input's own spacing moves to the wrapper, so the wrapper is
        // exactly the input's height and the button centers on it.
        const style = getComputedStyle(input);
        wrap.style.marginTop = style.marginTop;
        wrap.style.marginBottom = style.marginBottom;
        input.style.marginTop = "0";
        input.style.marginBottom = "0";

        const button = document.createElement("button");
        button.type = "button"; // never submits the form
        button.className = "password-toggle";
        wrap.appendChild(button);

        function render(visible) {
            button.innerHTML = visible ? EYE_OFF : EYE;
            button.setAttribute("aria-label", visible ? "Hide password" : "Show password");
            button.setAttribute("aria-pressed", String(visible));
        }
        render(false);

        button.addEventListener("click", () => {
            const visible = input.type === "password";
            input.type = visible ? "text" : "password";
            render(visible);
            input.focus();
        });

        // Don't leave the password readable once the form is sent.
        if (input.form) {
            input.form.addEventListener("submit", () => {
                input.type = "password";
                render(false);
            });
        }
    });
})();
