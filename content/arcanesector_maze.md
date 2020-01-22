Title: Arcanesector maze solver
Date: 2018-12-9 10:01
Modified: 2018-12-9 10:01
Category: misc
Tags: ctf, maze
Slug: arcanesector_maze
Authors: F3real
Summary: How to solve arcanesector maze

The Arcane sector is an old school (MMO)RPG game created by Gynvael for Dragon Sector CTF.

To get it running on local pc visit git repo and check instructions:
[Arcanesector Github](https://github.com/gynvael/arcanesector)

In this post, we will look at one of the tasks, maze.

First, we need to get `/server/data/map.json` which amongst other things contains a key for `terrain`.

We can load map with:

~~~python
def load_map():
    with open('map.json') as f:
        maze = json.load(f)['terrain']
        logging.debug(maze)
    return bytearray(maze.decode('base64').decode('zlib'))
~~~

Looking at data, we see that most of the values are in the range [0 - 10]. To visualize the map we have gotten we can use Python image library Pillow and map these values to colors. After tweaking the right colours and values we get:

![MMO(RPG) map]({static}/images/2018_12_9_map.png){: .img-fluid .centerimage}

And also we have gotten one of the flags by simply displaying map `DrgnS{LookBeyondTheHorizon}`.

From the map we can also get start and end coordinates of the maze:
~~~python
START = (11, 523)
END = (309, 597)
~~~

Since the maze is huge, a recursive solution will quickly run out of stack.
We could try raising the limit with `sys.setrecursionlimit(5000)` (default is usually `1k`) but it won't be enough. Raising it further will just cause python to crash, so let's look at the iterative solution.

The algorithm is just BFS (Breadth-First Search):

1. add start tile location to queue
2. take the first path from the queue (if empty exit) 
3. check if we have reached END tile
4. for each of possible moves (south, north, left, right)
    * check if it is possible (not wall or already seen), if possible mark it as seen and add it to queue
5. goto 2

Code:
~~~python
def solve_maze(maze):
    
    queue = Queue()
    queue.put([START])

    while not queue.empty():

        path = queue.get() 
        pos = path[-1]

        if pos == END:
            return path

        for move in MOVES:
            new_pos = (pos[0] + move[0], pos[1] + move[1])
            i = idx(*new_pos)
            if maze[i] == WALKABLE_INDOORS:
                # Mark tile as visited
                maze[i] = 0 
                new_path = list(path)
                new_path.append(new_pos)
                queue.put(new_path)
~~~

And let's look at our solution in action:
![Maze solving gif]({static}/images/2018_12_9_maze.gif){: .img-fluid .centerimage}

It takes around 7.6k steps to get to the exit.

Full solution can be found 
[here](https://github.com/F3real/ctf_solutions/tree/master/2018/arcane_sector).
