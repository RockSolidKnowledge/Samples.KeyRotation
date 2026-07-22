using System.ComponentModel.DataAnnotations;

namespace Samples.KeyRotation.OpenIddict.EntityFramework.ViewModels.Shared;

public class ErrorViewModel
{
    [Display(Name = "Error")]
    public string? Error { get; set; }

    [Display(Name = "Description")]
    public string? ErrorDescription { get; set; }
}
