#!/usr/bin/env ruby

####################################################
# tcpdump output parser for monitoring dns queries #
####################################################
#
# This is intended to be run as 
#   sudo tcpdump -vvv -s 0 -l -n port 53 | ./parse_tcpdump_dns.rb
#
# This is basically just a ruby port of Jon Tai's php script 
#   https://gist.github.com/jtai/1368338
#
# For more information, see his blog post where he explains it all
#   http://jontai.me/blog/2011/11/monitoring-dns-queries-with-tcpdump/
#

require 'optparse'
$options = {}
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: #{__FILE__} [OPTIONS]"
  opt.on("-f", "--follow", "Follow stuff") {|v| $options[:follow] = true }
  opt.on("-h", "--histogram", "Make a histogram") {|v| $options[:histogram] = true }
end
opt_parser.parse!

#defaults
$options[:follow] ||= false
$options[:histogram] ||= false

$queries = {}
$output = {}
$debug = nil

def output_real(timestamp, message)
  p "running real_output" if $debug
  printf("%s %s\n", timestamp, message)
end

def output(timestamp, message)
  p "running output" if $debug
  if $options[:follow]
    p "punting to real_output" if $debug
    output_real(timestamp, message)
  else
    # buffer output
    hm = timestamp[0..5]
    sa = timestamp[6]
    $output[hm] = {}
    $output[hm][sa] = [timestamp, message]
  end
end

def parse_timestamp(timestamp)
  hours = timestamp[0..2]
  minutes = timestamp[3..5]
  seconds = timestamp[6..-1]
  hours.to_i*3600 + minutes.to_i*60 + seconds.to_f
end

loop do
  line = ARGF.readline
  unless line =~ /^\d{2}:\d{2}:\d{2}\.\d+ IP [^>]+ > .+/
    line += ARGF.readline
  end

  puts line if $debug
  #query
  if line =~ /^(\d{2}:\d{2}:\d{2}\.\d+) IP [^>]+ > .+ (\d+)\+ (A(AAA)?)\? ([^ ]+)/
    qtimestamp = $1
    id = $2
    qtype = $3
    qsubject = $5.gsub(/\.$/, '')

    $queries[id] = [qtimestamp, qtype, qsubject]

    puts "found query" if $debug
    p $queries if $debug

    #response
  elsif line =~ /^(\d{2}:\d{2}:\d{2}\.\d+) IP [^>]+ > .+ (\d+).? q: (A(AAA)?)\? ([^ ]+)/
    rtimestamp = $1
    id = $2
    rtype = $3
    rsubject = $5.gsub(/\.$/, '')

    puts "found response" if $debug

    if $queries[id]
      puts "found matching query" if $debug
      qtimestamp, qtype, qsubject = $queries[id]
      if (rtype == qtype && qsubject == rsubject)
        puts "it all matches" if $debug
        ms = ((parse_timestamp(rtimestamp) - parse_timestamp(qtimestamp)) * 1000)
        bangs = [0, Math.log10(ms)].max.ceil

        output(qtimestamp, sprintf(
          "%- 4s %- 50s % 8.03f ms%s",
          qtype, qsubject, ms, bangs ? ' ' + '!'*bangs : ''
        ))
      else
        puts "doesn't match" if $debug
        output(qtimestamp, sprintf(
          "got response for query %s, but query type or subject doesn't match, query was %s %s, response was %s %s",
          id, qtype, qsubject, rtype, rsubject
        ))
      end
    else
      puts "unsolicited response" if $debug
      output(rtimestamp, sprintf(
        "got response to unsolicited %s query for %s (query %s)",
        rtype, rsubject, id
      ))
    end
    $queries.delete(id)
  end
end

unless $options[:follow]
  # look for queries without responses
  $queries.each do |id, query|
    qtimestamp, qtype, qsubject = query
    output(qtimestamp, sprintf(
      "%- 4s %- 50s        - ms **********",
      qtype, qsubject
    ))
  end

  # collate buffered output
  $output.each do |hm, bucket|
    bucket.sort.each do |sa,data|
      timestamp, message = data
      output_real(timestamp, message)
    end
  end

  # print histogram data
  if $options[:histogram]
    puts "\n\n\n"
    $output.each do |hm,bucket|
      # count failed queries
      failed = 0
      bucket.each do |sa,data|
        timestamp, message = data
        if message.index('- ms **********') != nil
          failed += 1
        end
      end
      printf("%s,%d\n", hm, failed)
    end
  end
end

