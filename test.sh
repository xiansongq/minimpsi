#!/bin/bash


# 判断文件是否存在并删除之前的 time_log.txt 文件
if [ -f "time_log.txt" ]; then
  rm time_log.txt
fi

# 定义测试函数
function run_test {
  echo "Running test -n: $1 -m: $2"
  ./out/build/linux/frontend/frontend -n $1 -m $2 -t 4 -r 0 >> time_log.txt
  #./frontend/frontend -n $1 -m $2 -t 4 -r 0 >> time_log.txt

  echo "Finished test -n: $1 -m: $2"
}

# 定义参数范围
n_values=(2 3 5 10 15 20 25 30 60 65 100)
m_values=(5 6 8 9 10)

# 运行循环测试
for n in "${n_values[@]}"; do
  for m in "${m_values[@]}"; do
    run_test $n $m
  done
done