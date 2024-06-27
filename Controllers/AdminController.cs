using Auth.Extensions;
using Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = ClsRoles.roleAdmin)]
    public class AdminController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public AdminController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        [HttpPost("AddRole")]
        public async Task<IActionResult> AddRole(RoleModel roleModel)
        {
            if (await _roleManager.RoleExistsAsync(roleModel.RoleName))
            {
                return Ok("this role is already existed !");
            }
            await _roleManager.CreateAsync(new IdentityRole(roleModel.RoleName));
            return Ok(roleModel.RoleName);
        }
    }
}
