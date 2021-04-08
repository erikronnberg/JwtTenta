using AutoMapper;

using JwtTenta.Models;
using JwtTenta.Models.Response;

namespace JwtTenta.Data
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<RegisterRequest, Account>().ReverseMap();
            CreateMap<AuthenticateResponse, Account>().ReverseMap();
            CreateMap<AccountResponse, Account>().ReverseMap();
            CreateMap<UpdateRequest, Account>()
                .ForSourceMember(x => x.Role, opt => opt.DoNotValidate())
                .ForSourceMember(x => x.Username, opt => opt.DoNotValidate())
                .ForSourceMember(x => x.NewPassword, opt => opt.DoNotValidate())
                .ForSourceMember(x => x.OldPassword, opt => opt.DoNotValidate());
            CreateMap<Account, Account>()
                .ForMember(x => x.Email, option => option.Ignore()).AfterMap((src, dst) => { if (src.Email != null) { dst.Email = src.Email; } })
                .ForMember(x => x.PhoneNumber, option => option.Ignore()).AfterMap((src, dst) => { if (src.PhoneNumber != null) { dst.PhoneNumber = src.PhoneNumber; } })
                .ForAllOtherMembers(option => option.Ignore());
            CreateMap<Orders, OrderResponse>();
        }
    }
}
