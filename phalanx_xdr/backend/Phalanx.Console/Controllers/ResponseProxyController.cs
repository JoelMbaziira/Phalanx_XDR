using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace Phalanx.Console.Controllers;

/// <summary>
/// Thin proxy: the browser posts to /api/response/issue (same origin),
/// and this controller forwards to the Ingestion service.
/// </summary>
[ApiController]
[Route("api/response")]
public class ResponseProxyController : ControllerBase
{
    private readonly IHttpClientFactory _http;
    private readonly IConfiguration _cfg;

    public ResponseProxyController(IHttpClientFactory http, IConfiguration cfg)
    {
        _http = http;
        _cfg  = cfg;
    }

    [HttpPost("issue")]
    public async Task<IActionResult> Issue([FromBody] JsonElement body)
    {
        if (body.ValueKind == JsonValueKind.Undefined || body.ValueKind == JsonValueKind.Null)
            return BadRequest(new { error = "Request body is required" });

        var ingestionBase = _cfg["Ingestion:BaseUrl"] ?? "http://localhost:5038";
        var client = _http.CreateClient();

        try
        {
            using var json = new StringContent(body.GetRawText(), System.Text.Encoding.UTF8, "application/json");
            var r = await client.PostAsync($"{ingestionBase}/api/v1/response/issue", json);
            var result = await r.Content.ReadAsStringAsync();

            if (!r.IsSuccessStatusCode)
                return StatusCode(502, result);

            try
            {
                return Ok(JsonSerializer.Deserialize<object>(result));
            }
            catch (JsonException ex)
            {
                return StatusCode(502, new
                {
                    error = "Invalid JSON returned by ingestion service",
                    detail = ex.Message,
                });
            }
        }
        catch (HttpRequestException ex)
        {
            return StatusCode(502, new
            {
                error = "Ingestion service unavailable",
                detail = ex.Message,
            });
        }
        catch (TaskCanceledException ex)
        {
            return StatusCode(502, new
            {
                error = "Ingestion service request timed out",
                detail = ex.Message,
            });
        }
        catch (Exception ex)
        {
            return StatusCode(502, new
            {
                error = "Failed to proxy response request",
                detail = ex.Message,
            });
        }
    }
}
