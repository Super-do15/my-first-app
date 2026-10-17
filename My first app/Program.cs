using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using System.Text.Json;

const int MaxImageBytes = 10 * 1024 * 1024;
const int MaxRequestBytes = 12 * 1024 * 1024;
const int PasswordIterations = 310_000;
var categories = new[] { "风景", "人文", "星空", "日常", "器材与技巧" };
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = MaxRequestBytes);
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 120,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));
    options.AddPolicy("authentication", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 10,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});
var dataDirectory = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
var uploadDirectory = Path.Combine(dataDirectory, "uploads");
Directory.CreateDirectory(uploadDirectory);
var store = new ForumStore(Path.Combine(dataDirectory, "forum.json"));
await store.InitializeAsync();
builder.Services.AddSingleton(store);
var sessions = new ConcurrentDictionary<string, ForumSession>();
var app = builder.Build();
app.UseRateLimiter();

app.MapGet("/", () => Results.File(Path.Combine(app.Environment.ContentRootPath, "index.html"), "text/html; charset=utf-8"));
app.MapGet("/uploads/{fileName}", (string fileName) =>
{
    if (fileName != Path.GetFileName(fileName)) return Results.NotFound();
    var path = Path.Combine(uploadDirectory, fileName);
    if (!File.Exists(path)) return Results.NotFound();
    var contentType = Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".jpg" => "image/jpeg",
        ".png" => "image/png",
        ".webp" => "image/webp",
        _ => "application/octet-stream"
    };
    return Results.File(path, contentType);
});

app.MapGet("/api/me", async (HttpContext context, ForumStore forum) =>
{
    var userId = GetUserId(context, sessions);
    if (userId is null) return Results.Ok(new { user = (PublicUser?)null });
    var user = await forum.ReadAsync(data => data.Users.FirstOrDefault(item => item.Id == userId));
    return Results.Ok(new { user = user is null ? null : ToPublicUser(user) });
});

app.MapPost("/api/register", async (HttpContext context, ForumStore forum) =>
{
    if (!IsSameOrigin(context)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    var input = await context.Request.ReadFromJsonAsync<AuthRequest>();
    var name = input?.Name?.Trim();
    var password = input?.Password;
    if (name is null || name.Length is < 2 or > 24 || password is null || password.Length is < 8 or > 128)
        return Results.BadRequest(new { error = "昵称需为 2 至 24 个字符，密码需为 8 至 128 个字符。" });

    var salt = RandomNumberGenerator.GetBytes(16);
    var user = new ForumUser
    {
        Id = Guid.NewGuid().ToString("N"),
        Name = name,
        PasswordSalt = Convert.ToBase64String(salt),
        PasswordHash = Convert.ToBase64String(HashPassword(password, salt)),
        CreatedAt = DateTimeOffset.UtcNow
    };
    var created = await forum.UpdateAsync(data =>
    {
        if (data.Users.Any(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase))) return false;
        data.Users.Add(user);
        return true;
    });
    if (!created) return Results.Conflict(new { error = "这个昵称已经被使用了。" });
    SetSession(context, sessions, user.Id);
    return Results.Ok(new { user = ToPublicUser(user) });
}).RequireRateLimiting("authentication");

app.MapPost("/api/login", async (HttpContext context, ForumStore forum) =>
{
    if (!IsSameOrigin(context)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    var input = await context.Request.ReadFromJsonAsync<AuthRequest>();
    var name = input?.Name?.Trim();
    var password = input?.Password;
    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrEmpty(password) || password.Length > 128)
        return Results.BadRequest(new { error = "请输入昵称和密码。" });
    var user = await forum.ReadAsync(data => data.Users.FirstOrDefault(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase)));
    if (user is null || !VerifyPassword(password, user.PasswordSalt, user.PasswordHash))
        return Results.Unauthorized();
    SetSession(context, sessions, user.Id);
    return Results.Ok(new { user = ToPublicUser(user) });
}).RequireRateLimiting("authentication");

app.MapPost("/api/logout", (HttpContext context) =>
{
    if (!IsSameOrigin(context)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    if (context.Request.Cookies.TryGetValue("shihen_session", out var token)) sessions.TryRemove(token, out _);
    context.Response.Cookies.Delete("shihen_session", new CookieOptions { Path = "/", SameSite = SameSiteMode.Strict, Secure = context.Request.IsHttps });
    return Results.Ok(new { ok = true });
});

app.MapGet("/api/posts", async (string? category, ForumStore forum) =>
{
    var posts = await forum.ReadAsync(data => data.Posts
        .Where(post => string.IsNullOrEmpty(category) || post.Category == category)
        .OrderByDescending(post => post.CreatedAt)
        .Take(100)
        .Select(post => new PostView(
            post.Id,
            post.Title,
            post.Category,
            post.Description,
            post.Place,
            post.ImageUrl,
            post.CreatedAt,
            data.Users.FirstOrDefault(user => user.Id == post.AuthorId)?.Name ?? "已注销用户",
            data.Comments.Where(comment => comment.PostId == post.Id)
                .OrderBy(comment => comment.CreatedAt)
                .Take(50)
                .Select(comment => new CommentView(
                    comment.Id,
                    data.Users.FirstOrDefault(user => user.Id == comment.AuthorId)?.Name ?? "已注销用户",
                    comment.Body,
                    comment.CreatedAt))
                .ToList()))
        .ToList());
    return Results.Ok(posts);
});

app.MapPost("/api/posts", async (HttpContext context, ForumStore forum) =>
{
    if (!IsSameOrigin(context)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    var userId = GetUserId(context, sessions);
    if (userId is null) return Results.Unauthorized();
    var form = await context.Request.ReadFormAsync();
    var title = form["title"].ToString().Trim();
    var category = form["category"].ToString();
    var description = form["description"].ToString().Trim();
    var place = form["place"].ToString().Trim();
    var image = form.Files.GetFile("image");
    if (title.Length is < 2 or > 100 || !categories.Contains(category) || description.Length > 2000 || place.Length > 100)
        return Results.BadRequest(new { error = "请检查标题、类别和文字长度。" });
    if (image is null || image.Length is 0 or > MaxImageBytes)
        return Results.BadRequest(new { error = "请上传一张不超过 10 MB 的照片。" });

    await using var imageStream = image.OpenReadStream();
    var header = new byte[12];
    var headerLength = await imageStream.ReadAsync(header.AsMemory(0, header.Length));
    var imageType = DetectImage(header, headerLength);
    if (imageType is null) return Results.BadRequest(new { error = "仅支持 JPG、PNG 或 WebP 图片。" });
    var fileName = $"{Guid.NewGuid():N}{imageType.Value.Extension}";
    var imagePath = Path.Combine(uploadDirectory, fileName);
    await using (var output = new FileStream(imagePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
    {
        await imageStream.CopyToAsync(output);
    }

    var post = new ForumPost
    {
        Id = Guid.NewGuid().ToString("N"),
        AuthorId = userId,
        Title = title,
        Category = category,
        Description = description,
        Place = place,
        ImageUrl = $"/uploads/{fileName}",
        CreatedAt = DateTimeOffset.UtcNow
    };
    await forum.UpdateAsync(data => { data.Posts.Add(post); return true; });
    return Results.Created("/api/posts", post);
});

app.MapPost("/api/posts/{postId}/comments", async (string postId, HttpContext context, ForumStore forum) =>
{
    if (!IsSameOrigin(context)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    var userId = GetUserId(context, sessions);
    if (userId is null) return Results.Unauthorized();
    var input = await context.Request.ReadFromJsonAsync<CommentRequest>();
    var body = input?.Body?.Trim();
    if (body is null || body.Length is < 1 or > 1000)
        return Results.BadRequest(new { error = "评论需为 1 至 1000 个字符。" });
    var comment = new ForumComment
    {
        Id = Guid.NewGuid().ToString("N"),
        PostId = postId,
        AuthorId = userId,
        Body = body,
        CreatedAt = DateTimeOffset.UtcNow
    };
    var exists = await forum.UpdateAsync(data =>
    {
        if (!data.Posts.Any(post => post.Id == postId)) return false;
        data.Comments.Add(comment);
        return true;
    });
    if (!exists) return Results.NotFound(new { error = "这篇作品不存在。" });
    return Results.Created($"/api/posts/{postId}/comments", comment);
});

app.Run();

static byte[] HashPassword(string password, byte[] salt)
{
    using var derivation = new Rfc2898DeriveBytes(password, salt, PasswordIterations, HashAlgorithmName.SHA256);
    return derivation.GetBytes(32);
}

static bool VerifyPassword(string password, string encodedSalt, string encodedHash)
{
    try
    {
        var salt = Convert.FromBase64String(encodedSalt);
        var expectedHash = Convert.FromBase64String(encodedHash);
        return CryptographicOperations.FixedTimeEquals(HashPassword(password, salt), expectedHash);
    }
    catch (FormatException)
    {
        return false;
    }
}

static bool IsSameOrigin(HttpContext context)
{
    var origin = context.Request.Headers.Origin.ToString();
    if (string.IsNullOrEmpty(origin)) return true;
    return Uri.TryCreate(origin, UriKind.Absolute, out var parsed)
        && string.Equals(parsed.Scheme, context.Request.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(parsed.Authority, context.Request.Host.Value, StringComparison.OrdinalIgnoreCase);
}

static string? GetUserId(HttpContext context, ConcurrentDictionary<string, ForumSession> sessions)
{
    if (!context.Request.Cookies.TryGetValue("shihen_session", out var token)
        || !sessions.TryGetValue(token, out var session)) return null;
    if (session.ExpiresAt > DateTimeOffset.UtcNow) return session.UserId;
    sessions.TryRemove(token, out _);
    return null;
}

static void SetSession(HttpContext context, ConcurrentDictionary<string, ForumSession> sessions, string userId)
{
    var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    sessions[token] = new ForumSession(userId, DateTimeOffset.UtcNow.AddDays(7));
    context.Response.Cookies.Append("shihen_session", token, new CookieOptions
    {
        HttpOnly = true,
        Secure = context.Request.IsHttps,
        SameSite = SameSiteMode.Strict,
        MaxAge = TimeSpan.FromDays(7),
        Path = "/"
    });
}

static (string Extension, string ContentType)? DetectImage(byte[] header, int length)
{
    if (length >= 3 && header[0] == 0xff && header[1] == 0xd8 && header[2] == 0xff) return (".jpg", "image/jpeg");
    if (length >= 8 && header.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 })) return (".png", "image/png");
    if (length >= 12 && header.AsSpan(0, 4).SequenceEqual("RIFF"u8) && header.AsSpan(8, 4).SequenceEqual("WEBP"u8)) return (".webp", "image/webp");
    return null;
}

static PublicUser ToPublicUser(ForumUser user) => new(user.Id, user.Name, user.CreatedAt);

sealed class ForumStore
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);
    private ForumData _data = new();

    public ForumStore(string filePath) => _filePath = filePath;

    public async Task InitializeAsync()
    {
        if (!File.Exists(_filePath)) return;
        await using var stream = File.OpenRead(_filePath);
        _data = await JsonSerializer.DeserializeAsync<ForumData>(stream, _json) ?? new ForumData();
    }

    public async Task<T> ReadAsync<T>(Func<ForumData, T> read)
    {
        await _mutex.WaitAsync();
        try { return read(_data); }
        finally { _mutex.Release(); }
    }

    public async Task<T> UpdateAsync<T>(Func<ForumData, T> update)
    {
        await _mutex.WaitAsync();
        try
        {
            var result = update(_data);
            var temporaryPath = $"{_filePath}.{Guid.NewGuid():N}.tmp";
            try
            {
                await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    await JsonSerializer.SerializeAsync(stream, _data, _json);
                File.Move(temporaryPath, _filePath, true);
            }
            finally
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }
            return result;
        }
        finally { _mutex.Release(); }
    }
}

sealed class ForumData
{
    public List<ForumUser> Users { get; set; } = new();
    public List<ForumPost> Posts { get; set; } = new();
    public List<ForumComment> Comments { get; set; } = new();
}

sealed class ForumUser
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string PasswordSalt { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

sealed class ForumPost
{
    public string Id { get; set; } = "";
    public string AuthorId { get; set; } = "";
    public string Title { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public string Place { get; set; } = "";
    public string ImageUrl { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

sealed class ForumComment
{
    public string Id { get; set; } = "";
    public string PostId { get; set; } = "";
    public string AuthorId { get; set; } = "";
    public string Body { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

sealed record ForumSession(string UserId, DateTimeOffset ExpiresAt);
sealed record AuthRequest(string? Name, string? Password);
sealed record CommentRequest(string? Body);
sealed record PublicUser(string Id, string Name, DateTimeOffset CreatedAt);
sealed record CommentView(string Id, string Author, string Body, DateTimeOffset CreatedAt);
sealed record PostView(string Id, string Title, string Category, string Description, string Place, string ImageUrl, DateTimeOffset CreatedAt, string Author, List<CommentView> Comments);
