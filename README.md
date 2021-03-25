# DotNetCore5ExternalGoogleLogin
Google Hesabı ile giriş yapılabilen .net identity ile postgre db de çalışan .net core 5 mvc projesidir.</br>

Bu proje esasında çeşitli identity denemelerimi yaptığım bir projedir üstünde google log in ve api aracılığı ile login geliştirmelerini ve örnek bir login sayfasını ekledim.</br>
Proje ef core 5.0 ile çalışıyor ve migration komutlarının çalışması için POSTGRESQL 10 sürümümün local pc nizde yüklü olması gerekiyor.</br>
Db nin oluşması için proje dizininde aşağıdaki migration komutunun çalıştırılması yeterlidir.</br>
update-database test-mig -Context AppIdentityDbContext
