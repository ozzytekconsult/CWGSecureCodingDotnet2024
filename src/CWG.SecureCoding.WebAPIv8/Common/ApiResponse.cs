using System.Collections.Generic;

namespace CWG.SecureCoding.WebAPIv8.Common
{
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public T Data { get; set; }
        public string Message { get; set; }
        public List<string> Errors { get; set; }
    }
}