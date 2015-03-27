#!/usr/bin/env ruby

require 'csv'
require 'pp'

ARGV.each do |file|
  puts "Opening #{file}"
  outputfile = CSV.open("YNAB-#{file}", "w")
  labels = []
  output = []

  CSV.foreach(file) do |row|
    # skip header row (or any others with only 1 cell)
    next if row.count == 1
    # set labels from first full row
    if labels.count == 0
      labels = row
      outputfile << %w(Date Payee Category Memo Outflow Inflow)
      next
    end

    output_row =  [
      row[labels.index('Date')],
      row[labels.index('Symbol')],
      '',
      row[labels.index('Description')]
    ]

    row[labels.index('Amount')].gsub!(/[^\d\.\-]/, '')
    output_row << '' if row[labels.index('Amount')].to_f >= 0
    output_row << row[labels.index('Amount')].to_f.abs

    outputfile << output_row
  end
end
