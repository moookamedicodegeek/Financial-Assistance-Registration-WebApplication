namespace Flow_Finance.Models
{
    public class FirebaseException
    {
        public Error error { get; set; }
    }
    public class Error
    {
        public int code { get; set; }
        public string message { get; set; }
        public List<Error> errors { get; set; }
    }

}
