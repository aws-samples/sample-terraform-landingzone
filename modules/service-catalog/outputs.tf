output "portfolio_ids" {
  description = "Map of portfolio name to portfolio ID"
  value = {
    for name, portfolio in aws_servicecatalog_portfolio.this : name => portfolio.id
  }
}

output "product_ids" {
  description = "Map of portfolio/product key to product ID"
  value = {
    for key, product in aws_servicecatalog_product.this : key => product.id
  }
}
