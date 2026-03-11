using System.Collections.Generic;
using System.Linq;
using CredentialVault.Core.Models;
using CredentialVault.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CredentialVault.Server.Controllers;

/// <summary>
/// REST API for the credential vault.
/// All endpoints require an API key in the X-Api-Key header.
/// Service department staff use the master API key; applications use application-specific keys.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "ApiKeyPolicy")]
public sealed class CredentialsController : ControllerBase
{
    private readonly VaultStore _vault;

    public CredentialsController(VaultStore vault)
    {
        _vault = vault;
    }

    /// <summary>
    /// Stores (creates or updates) a credential in the vault.
    /// </summary>
    [HttpPut]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult Store([FromBody] StoreCredentialRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        _vault.Store(request.Application, request.Key, request.PlainTextValue, request.Description);
        return Ok(new { message = "Credential stored successfully." });
    }

    /// <summary>
    /// Retrieves and returns the decrypted credential value.
    /// </summary>
    [HttpGet("{application}/{key}")]
    [ProducesResponseType(typeof(CredentialResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult Get(string application, string key)
    {
        var value = _vault.Retrieve(application, key);
        if (value is null)
            return NotFound(new { message = $"Credential '{key}' not found for application '{application}'." });

        return Ok(new CredentialResponse
        {
            Application = application,
            Key = key,
            Value = value
        });
    }

    /// <summary>
    /// Deletes a credential entry.
    /// </summary>
    [HttpDelete("{application}/{key}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult Delete(string application, string key)
    {
        var deleted = _vault.Delete(application, key);
        if (!deleted)
            return NotFound(new { message = $"Credential '{key}' not found for application '{application}'." });

        return NoContent();
    }

    /// <summary>
    /// Lists all credential keys for a given application (values are NOT returned).
    /// Intended for service department use.
    /// </summary>
    [HttpGet("{application}")]
    [ProducesResponseType(typeof(IEnumerable<object>), StatusCodes.Status200OK)]
    public IActionResult ListByApplication(string application)
    {
        var entries = _vault.ListByApplication(application);
        var result = entries.Select(e => new
        {
            e.Key,
            e.Description,
            e.CreatedAt,
            e.UpdatedAt
        });
        return Ok(result);
    }

    /// <summary>
    /// Lists all credential keys across all applications (values are NOT returned).
    /// Intended for service department use.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(IEnumerable<object>), StatusCodes.Status200OK)]
    public IActionResult ListAll()
    {
        var entries = _vault.ListAll();
        var result = entries.Select(e => new
        {
            e.Application,
            e.Key,
            e.Description,
            e.CreatedAt,
            e.UpdatedAt
        });
        return Ok(result);
    }
}
