using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> signinManager;
        private readonly UserManager<CognitoUser> userManager;
        private readonly CognitoUserPool cognitoUserPool;

        public AccountsController(SignInManager<CognitoUser> signinManager,
            UserManager<CognitoUser> userManager,
            CognitoUserPool cognitoUserPool)
        {
            this.signinManager = signinManager;
            this.userManager = userManager;
            this.cognitoUserPool = cognitoUserPool;
        }
        public async Task<IActionResult> Signup()
        {
            SignupModel model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                CognitoUser user = await cognitoUserPool.FindByIdAsync(model.Email);
                if(user != null)
                {
                    ModelState.AddModelError("User Exists", "User Exists");
                }else
                {
                    user = cognitoUserPool.GetUser(model.Email);
                    user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);
                    var newUser = await userManager.CreateAsync(user, model.Password);
                    if (newUser.Succeeded)
                    {
                        RedirectToAction("Confirm");
                    }
                }

            }
            return View(model);
        }

        public IActionResult Confirm()
        {
            ConfirmModel model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                CognitoUser user = await cognitoUserPool.FindByIdAsync(model.Email);
                if(user == null)
                {
                    ModelState.AddModelError("User Not Exists", "User Does Not Exists");

                }else
                {
                    var result = await (userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, false);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("index", "home");
                    }
                }


            }
            return View(model);
        }
        [HttpGet]
        public IActionResult Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> Authenticate(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await signinManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe,false);
                if (result.Succeeded)
                {
                    return RedirectToAction("index", "home");
                }
                else
                {
                    ModelState.AddModelError("Login failed", "Login failed");
                }
            }
            return View("Login",model);
        }

    }
}
