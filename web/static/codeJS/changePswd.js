validPasswd = false;
validPasswd2 = false;
setEventListeners()

function setEventListeners() {
    password = document.getElementById("new_pswd");
    password2 = document.getElementById("new_pswd2");

    password.addEventListener("input", (e) => validatePassword(password, password2));
    password2.addEventListener("input", (e) => validateSecPassword(password, password2));
}

function validatePassword(password, password2) {
    if (password.value.length < 8) {
        password.style.backgroundColor = "#FF0000";
        document.getElementById("passwd_err").style.display = "initial"
        document.getElementById("passwd_warning").style.display = "none"
        validPasswd = false
    } else {
        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[ `!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~])/
        if (password.value.match(regex)) {
            password.style.backgroundColor = "#00ff00";
            document.getElementById("passwd_err").style.display = "none"
            document.getElementById("passwd_warning").style.display = "none"
            document.getElementById("passwd_warning").style.color = "#00ff00"
            validPasswd = true
        } else {
            password.style.backgroundColor = "#999900";
            document.getElementById("passwd_err").style.display = "none"
            document.getElementById("passwd_warning").style.display = "initial"
            document.getElementById("passwd_warning").style.color = "#999900"
            validPasswd = true
        }
    }
    validateSecPassword(password, password2)
    validateSubmit()
}

function validateSecPassword(password, password2) {
    if (password.value != password2.value) {
        password2.style.backgroundColor = "#FF0000";
        document.getElementById("passwd2_err").style.display = "initial"
        validPasswd2 = false
    } else {
        password2.style.backgroundColor = "#00ff00";
        document.getElementById("passwd2_err").style.display = "none"
        validPasswd2 = true
    }
    validateSubmit()
}

function validateSubmit() {
    submit = document.getElementById("submit_button");
    if (validPasswd && validPasswd2) {
        submit.style.cursor = "default";
        submit.style.pointerEvents = "initial";
    } else {
        submit.style.cursor = "not_allowed";
        submit.style.pointerEvents = "none";
    }
}
