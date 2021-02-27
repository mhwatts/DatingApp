using System.Diagnostics.CodeAnalysis;
using API.Entities;
using Microsoft.EntityFrameworkCore;

namespace API.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<AppUser> Users { get; set; }



        #region Unused Code
        /*        
        public DataContext([NotNullAttribute] DbContextOptions options) : base(options)
        {
        } 
        */
        #endregion

    }
}