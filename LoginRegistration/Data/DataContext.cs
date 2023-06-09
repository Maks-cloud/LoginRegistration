﻿using LoginRegistration.Models;

namespace LoginRegistration.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
                
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            optionsBuilder.UseSqlServer("Server=.\\SQLEXPRESS;Database=myDataBase;Trusted_Connection=True;TrustServerCertificate=True;");               
        }

        public DbSet<User> Users { get; set; }
    }
}
