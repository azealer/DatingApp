using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {            
            this._repo = repo;
            this._config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(DtoRegUser dtoUser)
        {
            //validate request
            //if(!ModelState.IsValid)
            //    return BadRequest(ModelState);

            dtoUser.Username = dtoUser.Username.ToLower();
            if (await _repo.UserExists(dtoUser.Username))
            {
                return BadRequest("Username already exists");
            }

            var newUser = new User
            {
                Username = dtoUser.Username
            };

            var user = await _repo.Register(newUser, dtoUser.Password);

            return StatusCode(201);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(DtoLoginUser user)
        {
            var existUser = await _repo.Login(user.Username.ToLower(), user.Password);
            if (existUser == null) return Unauthorized();
            else
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, existUser.Id.ToString()),
                    new Claim(ClaimTypes.Name, existUser.Username)

                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));                
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
                
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.Now.AddDays(1),
                    SigningCredentials = creds
                };

                var tokenHanlder = new JwtSecurityTokenHandler();
                var token = tokenHanlder.CreateToken(tokenDescriptor);

                return Ok(new {
                    token = tokenHanlder.WriteToken(token)
                });
            }
        }
    }
}